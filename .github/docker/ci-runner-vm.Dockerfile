# syntax=docker/dockerfile:1
#
# pfBlockerNG CI runner image for the VM workloads (issue #2214) — smoke, the Web-UI
# tiers, the pfSense image build/refresh, and the version tracker's boot probe.
#
# It EXTENDS the non-VM image rather than restating it, so a VM leg and a non-VM leg can
# never grade under different ShellCheck/PHP/Python builds; BASE_IMAGE is pinned to the
# same .github/docker/VERSION tag and tests/test_ci_runner_images.py fails if it drifts.
#
# The added packages are exactly the `apt-get install` lists of the workflows this image
# replaces (smoke-single, ui-tests, build-image, image-refresh, version-tracker), plus
# the two tool downloads those workflows made through actions (oras) and a pip step
# (Playwright's Chromium build).
#
# RUNTIME REQUIREMENT: /dev/kvm must be passed into the container. tests/smoke/boot_vm.sh
# boots the guest with `-enable-kvm -cpu host` and the workflow asserts the device before
# calling it — a FreeBSD guest under TCG is not merely slower, it times the suite out.

ARG BASE_IMAGE=ghcr.io/pfblockerng/ci-runner:1
FROM ${BASE_IMAGE}

LABEL org.opencontainers.image.source=https://github.com/pfBlockerNG/pfBlockerNG
LABEL org.opencontainers.image.description="pfBlockerNG CI toolchain (VM workflows: qemu, oras, Playwright)"

ENV DEBIAN_FRONTEND=noninteractive

# qemu-system-x86 + qemu-utils boot the guest and build the overlay qcow2; dnsutils is
# `dig` (the DNSBL assertions); openssh-client is the ssh/scp round-trip every on-box
# step rides. The guest reaches the host through SLIRP user networking and a QEMU socket
# NIC (boot_vm.sh), so no tap/bridge privileges are needed — only /dev/kvm.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      dnsutils openssh-client qemu-system-x86 qemu-utils \
 && rm -rf /var/lib/apt/lists/*

# oras pulls/pushes the pfSense qcow2 images stored as OCI artifacts in GHCR. Replaces
# oras-project/setup-oras@v2, which resolved a floating latest on every run.
ARG ORAS_VERSION=1.3.3
ARG ORAS_SHA256=9ce999f8d2de03fc03968b29d743077a58783e545e5eaa53917ca177352d0e59
RUN curl -fsSLo /tmp/oras.tar.gz \
      "https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/oras_${ORAS_VERSION}_linux_amd64.tar.gz" \
 && echo "${ORAS_SHA256}  /tmp/oras.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/oras.tar.gz -C /tmp oras \
 && install -m 0755 /tmp/oras /usr/local/bin/oras \
 && rm -f /tmp/oras.tar.gz /tmp/oras

# The smoke harness's Python dependencies, pinned by tests/smoke/requirements.txt itself
# (the workflows install that same file at runtime; baking it makes that a no-op instead
# of a per-job download). --with-deps pulls Chromium's shared libraries through apt, and
# PLAYWRIGHT_BROWSERS_PATH puts the browser build in a fixed location so the runtime
# install finds it already present.
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright
COPY tests/smoke/requirements.txt /opt/smoke-requirements.txt
COPY .github/docker/check-chromium.py /tmp/check-chromium.py
# `--with-deps` shells out to apt itself, so the package lists have to be present in THIS
# layer — every earlier layer drops them to keep the image small.
RUN apt-get update \
 && python3 -m pip install --no-cache-dir -r /opt/smoke-requirements.txt \
 && python3 -m playwright install --with-deps chromium \
 && rm -rf /var/lib/apt/lists/*

# Same contract as the base image: a dependency that cannot actually run fails the BUILD,
# not the first smoke leg 40 minutes into a matrix.
RUN set -eu; \
    qemu-system-x86_64 --version; \
    qemu-img --version; \
    oras version; \
    ssh -V; \
    dig -v; \
    python3 -c 'import dns.resolver, playwright, pytest, requests'; \
    python3 /tmp/check-chromium.py; \
    rm -f /tmp/check-chromium.py
