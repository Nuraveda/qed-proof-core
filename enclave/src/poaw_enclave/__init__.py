"""poaw-enclave: the guest that runs inside the AWS Nitro Enclave (docs: README.md, protocol C4)."""
VSOCK_PORT = 5005          # host -> enclave requests
PARENT_CID = 3             # the parent instance, as seen from inside the enclave
FORWARD_VSOCK_PORT = 8443  # host vsock-proxy -> api.github.com:443
