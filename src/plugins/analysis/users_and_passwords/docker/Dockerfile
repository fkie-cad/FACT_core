FROM alpine:3.18

RUN apk add --no-cache john curl

WORKDIR /work

RUN touch temp.txt && \
    curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt >> temp.txt && \
    curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Honeypot-Captures/multiplesources-passwords-fabian-fingerle.de.txt >> temp.txt && \
    curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Default-Credentials/cirt-net_collection.txt >> temp.txt && \
    curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt | awk -F ':' '{print $2}' >> temp.txt && \
    curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Default-Credentials/Routers/0ALL-USERNAMES-AND-PASSWORDS.txt >> temp.txt && \
    cat temp.txt | sort | uniq > wordlist.txt && \
    rm temp.txt
COPY entry.sh .

ENTRYPOINT ["/work/entry.sh"]
