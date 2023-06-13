FROM python:3.11

# install rizin
ARG rizin_version="v0.5.2"
RUN wget https://github.com/rizinorg/rizin/releases/download/${rizin_version}/rizin-${rizin_version}-static-x86_64.tar.xz && \
    tar xf rizin-${rizin_version}-static-x86_64.tar.xz && \
    rm rizin-${rizin_version}-static-x86_64.tar.xz

# clone FwHunt rules
WORKDIR /work/FwHunt
ARG fwhunt_sha="8906b6bc48dbed3f6005d8e842474f9b1e709003"
RUN git init && \
    git remote add origin https://github.com/binarly-io/fwhunt && \
    git fetch --depth 1 origin ${fwhunt_sha} && \
    git checkout FETCH_HEAD

# install fwhunt-scan
RUN python3 -m pip install --no-cache-dir fwhunt-scan

COPY scan.py .

ENTRYPOINT ["/work/FwHunt/scan.py"]
