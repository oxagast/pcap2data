// eslint.config.js — PacketSnitch ESLint configuration (flat format, ESLint v9+)

const testFiles = ['tests/**/*.test.js', 'tests/**/*.spec.js'];
const webpackFiles = ['webpack.*.js', 'scripts/**/*.js', 'forge.config.js', '*.spec.js', 'snitch*.spec'];
const srcFiles = ['src/**/*.js'];

module.exports = [
    // --- Shared globals & parser options ---
    {
        languageOptions: {
            ecmaVersion: 2020,
            sourceType: 'module',
            globals: {
                browser: true,
                node: true,
                es2020: true,
            },
        },
        rules: {
            // General
            'no-console': 'off',
            'no-debugger': 'warn',
            'no-eval': 'error',
            'no-with': 'error',
            'no-proto': 'error',
            'no-script-url': 'error',

            // Spacing & style
            'indent': ['error', 2, { SwitchCase: 1 }],
            'linebreak-style': ['error', 'unix'],
            'quotes': ['error', 'single', { avoidEscape: true }],
            'semi': ['error', 'always'],
            'comma-dangle': ['error', 'always-multiline'],
            'max-len': ['error', { code: 120, ignoreStrings: true, ignoreTemplateLiterals: true }],
            'brace-style': ['error', '1tbs', { allowSingleLine: false }],
            'keyword-spacing': 'error',
            'space-before-blocks': 'error',
            'array-bracket-spacing': ['error', 'never'],
            'object-curly-spacing': ['error', 'always'],
            'comma-spacing': 'error',
            'comma-style': ['error', 'last'],
            'arrow-spacing': 'error',
            'arrow-parens': ['error', 'always'],
            'arrow-body-style': ['error', 'as-needed', { requireReturnForObjectLiteral: false }],
            'consistent-return': 'warn',
            'eqeqeq': ['error', 'always'],
            'yoda': 'error',

            // Best practices
            'consistent-this': ['error', 'self'],
            'no-caller': 'error',
            'no-div-regex': 'error',
            'no-else-return': ['warn', { allowElseIf: false }],
            'no-empty-function': 'error',
            'no-extra-bind': 'error',
            'no-extra-label': 'error',
            'no-floating-decimal': 'error',
            'no-labels': 'error',
            'no-lone-blocks': 'error',
            'no-loop-func': 'error',
            'no-multi-spaces': 'error',
            'no-multi-str': 'error',
            'no-new': 'error',
            'no-new-func': 'error',
            'no-new-wrappers': 'error',
            'no-octal': 'error',
            'no-octal-escape': 'error',
            'no-param-reassign': 'warn',
            'no-redeclare': 'error',
            'no-return-assign': ['error', 'always'],
            'no-self-compare': 'error',
            'no-sequences': 'error',
            'no-throw-literal': 'error',
            'no-unmodified-loop-condition': 'error',
            'no-useless-call': 'warn',
            'no-useless-concat': 'warn',
            'no-useless-escape': 'error',
            'no-useless-return': 'warn',
            'no-void': 'error',
            'no-warning-comments': 'off',
            'prefer-promise-reject-errors': ['error', { allowEmptyReject: true }],
            'require-await': 'warn',
            'wrap-iife': ['error', 'outside'],

            // ES2015+
            'object-shorthand': ['error', 'always'],
            'prefer-const': ['error', { destructuring: 'any', ignoreReadBeforeAssign: false }],
            'no-var': 'error',
            'rest-spread-spacing': ['error', 'never'],
            'template-curly-spacing': ['error', 'never'],
            'yield-star-spacing': ['error', 'after'],
        },
    },

    // --- Test files: Jest globals, relaxed rules ---
    {
        files: testFiles,
        languageOptions: {
            globals: { jest: true, describe: true, it: true, expect: true, beforeEach: true, afterEach: true, beforeAll: true, afterAll: true },
        },
        rules: {
            'no-unused-vars': 'off',
            'no-prototype-builtins': 'off',
        },
    },

    // --- Webpack / build scripts ---
    {
        files: webpackFiles,
        languageOptions: {
            globals: { node: true },
        },
        rules: {
            'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
        },
    },

    // --- Src files: strictest ---
    {
        files: srcFiles,
        rules: {
            'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
            'no-implicit-globals': 'error',
            'no-shadow': 'error',
            'no-shadow-restricted-names': 'error',
            'no-undef': 'error',
            'no-dupe-keys': 'error',
            'no-duplicate-case': 'error',
            'valid-typeof': 'error',
            'no-empty': 'error',
            'no-ex-assign': 'error',
            'no-const-assign': 'error',
            'no-new-require': 'error',
            'no-path-concat': 'error',
            'no-process-exit': 'error',
            'no-trailing-spaces': 'error',
            'space-infix-ops': 'error',
        },
    },
];
