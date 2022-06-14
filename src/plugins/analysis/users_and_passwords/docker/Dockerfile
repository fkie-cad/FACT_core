FROM alpine:3.14

RUN apk add --no-cache john curl

WORKDIR /work

RUN curl https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt > 10k-most-common.txt
COPY entry.sh .

ENTRYPOINT ["/work/entry.sh"]
