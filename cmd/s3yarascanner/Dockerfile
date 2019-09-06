FROM ubuntu:18.04
#BUILD libyara.so.3 from latest source
RUN apt-get update
RUN apt-get install -y git curl gcc automake libtool make flex bison
RUN mkdir virustotal
RUN cd virustotal ; git clone https://github.com/virustotal/yara
WORKDIR /virustotal/yara
ENV YARA_SRC /virustotal/yara
RUN ./bootstrap.sh && ./configure && make -C ${YARA_SRC} && make -C ${YARA_SRC} install
ENV LD_LIBRARY_PATH $LD_LIBRARY_PATH:/usr/local/lib
#libyara3 should be loaded now
WORKDIR /go
ARG RULESDIR
ARG BINARYDIR
ARG SQLITEDB
ARG FEEDSERVERTEMPLATEFILE
ENV FEEDSERVERTEMPLATEFILE ${FEEDSERVERTEMPLATEFILE:-./feed.tmpl}
ENV SQLITEDB ${SQLITEDB:-./db/results.db}
ENV RULESDIR ${RULESDIR:-./rules}
ENV BINARYDIR ${BINARYDIR:-./bins}
RUN mkdir $BINARYDIR
RUN mkdir $RULESDIR
RUN mkdir db
#windows docker support is still lack-luster in 2019 -- uncommment if running on WINDERS/WSL1
COPY . /go
RUN chmod +x /go/s3yarascanner
#End of win-sepcific dockerfile block
ENV PATH $PATH:$HOME/.local/bin
ENTRYPOINT ["/bin/bash"]
#entrypoint is bash , with args from Command array
CMD ["-c","ls -R /go ; /go/s3yarascanner"]