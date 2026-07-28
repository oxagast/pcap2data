echo "Installing PacketSnitch Metrics Server"

mkdir -p /var/log/packetsnitch-metrics
cp src/metrics/ps-metrics.py /usr/local/bin/
cp src/metrics/packetsnitch-metrics.service /usr/lib/systemd/system/
chmod a+rx,u+rwx /usr/local/bin/ps-metrics.py
chown root:root /usr/lib/systemd/system/packetsnitch-metrics.service
chown packetsnitch:packetsnitch /var/log/packetsnitch-metrics -R
systemctl daemon-reload
systemctl enable --now packetsnitch-metrics
systemctl start packetsnitch-metrics
curl -s http://127.0.0.1:8088/healthz | jq