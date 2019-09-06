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
ENV FEEDSERVERTEMPLATEFILE ${FEEDSERVERTEMPLATEFILE:-/go/cmd/s3yarascanner/feed.tmpl}
ENV SQLITEDB ${SQLITEDB:-/go/db/results.db}
ENV RULESDIR ${RULESDIR:-/go/rules}
ENV BINARYDIR ${BINARYDIR:-/go/bins}
RUN mkdir $BINARYDIR
RUN mkdir /db
#COPY ./s3yarascanner /go/s3yarascanner
#COPY $FEEDSERVERTEMPLATEFILE /go/$FEEDSERVERTEMPLATEFILE
#RUN chmod +x s3yarascanner
ENV PATH $PATH:$HOME/.local/bin
ENTRYPOINT ["/bin/bash"]
#entrypoint is bash , with args from Command array
CMD ["-c","ls -R /vol ; /vol/cmd/s3yarascanner/s3yarascanner"]