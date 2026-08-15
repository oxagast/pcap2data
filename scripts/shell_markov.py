#!/usr/bin/env python3
"""Character-level Markov model for probabilistic shell-command reconstruction.

Trains on one command per line.  The model stores n-gram transition counts,
command length priors, first-token priors, and simple QWERTY key distances.
It can rank supplied candidate commands or generate high-probability commands
for an approximate target length.
"""
from __future__ import annotations

import argparse, json, math, random, re
from collections import Counter, defaultdict
from pathlib import Path

BOS = "\u0002"
EOS = "\u0003"

# Approximate unshifted/shifted QWERTY coordinates. Shifted symbols inherit key location.
_ROWS = [
    ("`1234567890-=", 0.0),
    ("qwertyuiop[]\\", 0.25),
    ("asdfghjkl;'", 0.5),
    ("zxcvbnm,./", 0.75),
]
SHIFT = {
    '~':'`','!':'1','@':'2','#':'3','$':'4','%':'5','^':'6','&':'7','*':'8','(':'9',')':'0',
    '_':'-','+':'=','{':'[','}':']','|':'\\',':':';','"':"'",'<':',','>':'.','?':'/'
}
QPOS = {}
for y,(row,off) in enumerate(_ROWS):
    for x,ch in enumerate(row):
        QPOS[ch] = (x + off, float(y))
        QPOS[ch.upper()] = (x + off, float(y))
for a,b in SHIFT.items():
    QPOS[a] = QPOS[b]
QPOS[' '] = (5.0, 4.0)


def key_distance(a: str, b: str) -> float:
    pa, pb = QPOS.get(a), QPOS.get(b)
    if not pa or not pb:
        return 1.5
    return math.dist(pa, pb)


def clean_lines(path: str):
    for raw in Path(path).read_text(errors='replace').splitlines():
        s = raw.rstrip('\r\n')
        if not s.strip():
            continue
        # Keep the command mostly verbatim. Collapse pathological indentation only.
        s = re.sub(r'^\s{2,}', '', s)
        yield s


class ShellMarkov:
    def __init__(self, order=4, alpha=0.05):
        self.order = order
        self.alpha = alpha
        self.counts = defaultdict(Counter)
        self.context_totals = Counter()
        self.vocab = Counter()
        self.lengths = Counter()
        self.first_tokens = Counter()
        self.command_counts = Counter()
        self.n_commands = 0

    def train(self, commands):
        k = self.order - 1
        for cmd in commands:
            self.n_commands += 1
            self.command_counts[cmd] += 1
            self.lengths[len(cmd)] += 1
            tok = cmd.strip().split(maxsplit=1)[0] if cmd.strip() else ''
            if tok:
                self.first_tokens[tok] += 1
            seq = BOS*k + cmd + EOS
            for i in range(k, len(seq)):
                ctx = seq[i-k:i]
                ch = seq[i]
                self.counts[ctx][ch] += 1
                self.context_totals[ctx] += 1
                self.vocab[ch] += 1
        return self

    @property
    def alphabet(self):
        return sorted(self.vocab)

    def trans_logp(self, ctx, ch):
        c = self.counts.get(ctx)
        V = max(1, len(self.vocab))
        n = c.get(ch,0) if c else 0
        total = self.context_totals.get(ctx,0)
        return math.log((n+self.alpha)/(total+self.alpha*V))

    def command_logp(self, cmd, include_length=True):
        k = self.order - 1
        seq = BOS*k + cmd + EOS
        lp = 0.0
        n = 0
        for i in range(k, len(seq)):
            lp += self.trans_logp(seq[i-k:i], seq[i])
            n += 1
        # normalize somewhat by sequence length so longer candidates are not crushed
        lp /= max(1,n)
        if include_length:
            total = sum(self.lengths.values())
            lp += 0.35 * math.log((self.lengths.get(len(cmd),0)+1)/(total+len(self.lengths)))
        if cmd in self.command_counts:
            lp += 0.25 * math.log1p(self.command_counts[cmd])
        return lp

    def timing_score(self, cmd, delays_ms):
        """Heuristic score for command-vs-delay compatibility.

        It does NOT claim exact key recovery. It rewards a weak empirical assumption:
        longer QWERTY moves / shifted punctuation tend to tolerate somewhat longer delays.
        Delays are z-normalized, so only relative rhythm matters.
        """
        if not delays_ms or len(cmd) < 2:
            return 0.0
        ds = list(map(float, delays_ms[:max(0,len(cmd)-1)]))
        if len(ds) < 2:
            return 0.0
        ds_sorted = sorted(ds)
        med = ds_sorted[len(ds_sorted)//2]
        mad_vals = sorted(abs(x-med) for x in ds)
        mad = mad_vals[len(mad_vals)//2] or 1.0
        z = [max(-3,min(3,(d-med)/(1.4826*mad))) for d in ds]
        moves=[]
        for a,b in zip(cmd, cmd[1:]):
            d=key_distance(a,b)
            # shift/punctuation gets a modest extra cost
            if b in SHIFT or b in '|{}[]()"\'<>?:_+~!@#$%^&*':
                d += 0.55
            moves.append(d)
        if len(moves) > len(z):
            moves=moves[:len(z)]
        if len(z) > len(moves):
            z=z[:len(moves)]
        if len(moves)<2:
            return 0.0
        mm=sum(moves)/len(moves)
        mv=math.sqrt(sum((x-mm)**2 for x in moves)/len(moves)) or 1.0
        mz=[(x-mm)/mv for x in moves]
        # negative MSE => higher is better
        mse=sum((a-b)**2 for a,b in zip(mz,z))/len(z)
        return -mse

    def score(self, cmd, delays_ms=None, timing_weight=0.22):
        s=self.command_logp(cmd)
        if delays_ms:
            s += timing_weight*self.timing_score(cmd,delays_ms)
        return s

    def rank(self, candidates, delays_ms=None, timing_weight=0.22):
        out=[]
        for c in candidates:
            out.append((self.score(c,delays_ms,timing_weight),c))
        return sorted(out, reverse=True)

    def generate_beam(self, target_len=None, tolerance=3, beam=500, max_len=120, topn=30):
        """Beam-search likely strings. target_len excludes EOS."""
        k=self.order-1
        states=[(0.0, BOS*k, '')]
        finals=[]
        vocab=[c for c in self.alphabet if c not in (BOS,)]
        for _ in range(max_len+1):
            nxt=[]
            for score,ctx,text in states:
                cands=self.counts.get(ctx)
                if not cands:
                    continue
                # Limit branching to observed next chars, strongest first.
                for ch,_ in cands.most_common(24):
                    ns=score+self.trans_logp(ctx,ch)
                    if ch==EOS:
                        L=len(text)
                        if target_len is None or abs(L-target_len)<=tolerance:
                            # length prior and duplicate-history bonus
                            final=self.command_logp(text)
                            finals.append((final,text))
                        continue
                    if target_len is not None and len(text) >= target_len+tolerance:
                        continue
                    nt=text+ch
                    nctx=(ctx+ch)[-k:]
                    nxt.append((ns,nctx,nt))
            nxt.sort(reverse=True,key=lambda x:x[0]/max(1,len(x[2])))
            states=nxt[:beam]
            if not states:
                break
        # deduplicate
        best={}
        for s,t in finals:
            best[t]=max(s,best.get(t,-1e99))
        return sorted(((s,t) for t,s in best.items()),reverse=True)[:topn]

    def to_dict(self):
        return {
            'model_type':'character_markov_shell_command_prior',
            'order':self.order,
            'alpha':self.alpha,
            'n_commands':self.n_commands,
            'vocab':dict(self.vocab),
            'lengths':dict(self.lengths),
            'first_tokens':dict(self.first_tokens),
            'command_counts':dict(self.command_counts),
            'transitions':{ctx:dict(cnt) for ctx,cnt in self.counts.items()},
        }

    @classmethod
    def from_dict(cls,d):
        m=cls(d['order'],d.get('alpha',0.05))
        m.n_commands=d['n_commands']
        m.vocab=Counter(d['vocab'])
        m.lengths=Counter({int(k):v for k,v in d['lengths'].items()})
        m.first_tokens=Counter(d['first_tokens'])
        m.command_counts=Counter(d.get('command_counts',{}))
        for ctx,cnt in d['transitions'].items():
            m.counts[ctx]=Counter(cnt)
            m.context_totals[ctx]=sum(cnt.values())
        return m


def load_delays(path):
    d=json.loads(Path(path).read_text())
    return [x['delayMs'] for x in d.get('delays',[]) if isinstance(x.get('delayMs'),(int,float))]


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--corpus',default='/mnt/data/shell_corpus.txt(1)')
    ap.add_argument('--order',type=int,default=4,help='n-gram order (default 4 = trigram context -> next char)')
    ap.add_argument('--save')
    ap.add_argument('--load')
    ap.add_argument('--target-length',type=int)
    ap.add_argument('--tolerance',type=int,default=3)
    ap.add_argument('--generate',type=int,default=20)
    ap.add_argument('--rank-file',help='one candidate command per line')
    ap.add_argument('--timing-json',help='PacketSnitch keys JSON; uses delay rhythm only when ranking')
    args=ap.parse_args()

    if args.load:
        model=ShellMarkov.from_dict(json.loads(Path(args.load).read_text()))
    else:
        cmds=list(clean_lines(args.corpus))
        model=ShellMarkov(args.order).train(cmds)
        print(f'trained: {model.n_commands} lines, {len(model.command_counts)} unique commands, {len(model.vocab)} chars')

    if args.save:
        Path(args.save).write_text(json.dumps(model.to_dict(),separators=(',',':')))
        print('saved',args.save)

    delays=load_delays(args.timing_json) if args.timing_json else None

    if args.rank_file:
        candidates=list(clean_lines(args.rank_file))
        for s,c in model.rank(candidates,delays)[:args.generate]:
            print(f'{s: .5f}\t{c}')
    elif args.target_length is not None:
        for s,c in model.generate_beam(args.target_length,args.tolerance,topn=args.generate):
            print(f'{s: .5f}\t{c}')
    else:
        print('top command tokens:')
        for tok,n in model.first_tokens.most_common(30):
            print(f'{n:5d}  {tok}')

if __name__=='__main__':
    main()
