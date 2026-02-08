### Advanced Intrusion Detection Environment
---

```bash
# Run:
sudo python3 configure_aide.py --verbose --json

# Check logs:
tail -f /var/log/aide_config.log
tail -f /var/log/aide_config.json | jq

# Verify timer:
systemctl status aidecheck.timer

# Docker/Podman:
podman|docker build -t aide .
podman|docker run --rm --cap-add SYS_ADMIN -v /etc/aide:/etc/aide -v /var/log:/var/log -v /var/backups:/var/backups aide

# Kubernetes:
kubectl apply -f container.yaml
kubectl get pods
```