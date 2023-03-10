FROM alpine

RUN apk add ctags python3 python3-dev py3-pip libc-dev gcc bash curl
RUN pip install wheel python-ctags3 simplejson

WORKDIR /opt/generate_syscalls
COPY ./generate_syscalls.sh ./generate_syscalls.sh
RUN ./generate_syscalls.sh

COPY ./syscalls_from_tbl.py ./syscalls_from_tbl.py
COPY ./a.sh ./a.sh
RUN ./a.sh

CMD cat syscalls.json
