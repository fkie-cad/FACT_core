FROM alpine:3.14

RUN apk add --no-cache john curl

WORKDIR /work

RUN curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt > common.txt && \
    curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Honeypot-Captures/multiplesources-passwords-fabian-fingerle.de.txt > honeypot_cap.txt && \
    curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt | awk -F ':' '{print $2}' > ssh.txt && \
    cat common.txt honeypot_cap.txt ssh.txt | sort | uniq > wordlist.txt && \
    rm common.txt honeypot_cap.txt ssh.txt
COPY entry.sh .

ENTRYPOINT ["/work/entry.sh"]
