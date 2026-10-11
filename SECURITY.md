# Security Policy

Do not run untrusted code with the process backend. It does not enforce network,
filesystem, CPU, memory, or disk isolation. The default network-deny policy fails
closed because process mode cannot guarantee network isolation. Do not enable the
unsafe acknowledgement for untrusted workloads. Report vulnerabilities privately
and never include credentials, private keys, or sensitive audit logs.
