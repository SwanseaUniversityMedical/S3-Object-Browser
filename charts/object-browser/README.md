# Installing the Object Browser Helm Chart

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+
- kubectl configured to access your cluster

## Installation

### Basic Installation

```bash
# Add the repository (if using a remote repo)
helm repo add object-browser https://example.com/charts
helm repo update

# Install the chart
helm install my-release object-browser/object-browser --namespace object-browser --create-namespace
```

### Customized Installation

```bash
# Install with custom values
helm install my-release object-browser/object-browser \
  --namespace object-browser \
  --create-namespace \
  -f values.yaml \
  --set objectBrowser.keycloak.idpPublicUrl=https://keycloak.example.com/realms/object-browser \
  --set objectBrowser.ingress.enabled=true \
  --set objectBrowser.ingress.hosts[0].host=object-browser.example.com
```

## Configuration

### Key Values

| Parameter | Description | Default |
|-----------|-------------|---------|
| `postgres.enabled` | Enable PostgreSQL | `true` |
| `keycloak.enabled` | Enable Keycloak OIDC | `true` |
| `minio.enabled` | Enable MinIO S3 storage | `true` |
| `objectBrowser.enabled` | Enable Object Browser app | `true` |
| `objectBrowser.image.tag` | Application image tag | `latest` |
| `objectBrowser.replicas` | Number of app replicas | `1` |
| `objectBrowser.keycloak.idpPublicUrl` | Keycloak public URL for browser | `http://localhost:8080/realms/object-browser` |
| `objectBrowser.ingress.enabled` | Enable ingress | `false` |

### Production Configuration

```yaml
# values-prod.yaml
keycloak:
  environment:
    KC_HOSTNAME_STRICT_HTTPS: "true"
    KC_LOG_LEVEL: "warn"

objectBrowser:
  replicas: 3
  keycloak:
    insecureSkipVerify: "false"
  security:
    csrfCookieSecure: "true"
    sessionCookieSecure: "true"
  ingress:
    enabled: true
    className: nginx
    hosts:
      - host: object-browser.example.com
        paths:
          - path: /
            pathType: Prefix
    tls:
      - secretName: object-browser-tls
        hosts:
          - object-browser.example.com

minio:
  ingress:
    enabled: true
    className: nginx
    hosts:
      - host: minio.example.com
        paths:
          - path: /
            pathType: Prefix

postgres:
  persistence:
    size: 100Gi
    storageClassName: fast-ssd
```

### Installation with Production Values

```bash
helm install my-release object-browser/object-browser \
  --namespace object-browser \
  --create-namespace \
  -f values-prod.yaml
```

## Upgrade

```bash
# Update the chart
helm upgrade my-release object-browser/object-browser \
  --namespace object-browser \
  -f values.yaml
```

## Uninstall

```bash
# Remove the release
helm uninstall my-release --namespace object-browser

# (Optional) Remove the namespace
kubectl delete namespace object-browser
```

## Verify Installation

```bash
# Check deployment status
kubectl get deployments -n object-browser

# Check pods
kubectl get pods -n object-browser

# View logs
kubectl logs -n object-browser -l app=object-browser -f

# Port forward to access locally
kubectl port-forward -n object-browser svc/object-browser 9090:9090
kubectl port-forward -n object-browser svc/keycloak 8080:8080
```

## Troubleshooting

### Keycloak fails to start

Check PostgreSQL is running:
```bash
kubectl logs -n object-browser deployment/postgres
```

### Object Browser can't connect to Keycloak

Verify the `CONSOLE_IDP_PUBLIC_URL` is accessible from your browser. For local testing, it should be `http://localhost:8080`, not `http://keycloak:8080`.

### Persistent volumes not available

Check available storage classes:
```bash
kubectl get storageclass
```

Update the storage class in values:
```yaml
postgres:
  persistence:
    storageClassName: your-storage-class
```

## Support

For issues or questions, please refer to the Object Browser documentation or GitHub repository.
