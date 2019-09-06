FROM ubuntu:18.04
ARG RULESDIR
ARG BINARYDIR
ARG FEEDSERVERTEMPLATEFILE
ENV FEEDSERVERTEMPLATEFILE ${FEEDSERVERTEMPLATEFILE:-./feed.tmpl}
COPY $FEEDSERVERTEMPLATEFILE .
ENV RULESDIR ${RULESDIR:-./rules}
ENV BINARYDIR ${BINARYDIR:-./bins}
WORKDIR /go
RUN mkdir $RULESDIR
RUN mkdir $BINARYDIR
RUN mkdir ./db
COPY ./s3yarascanner /go/s3yarascanner
RUN chmod +x s3yarascanner
#BUILD libyara.so.3 from latest source
RUN apt-get update
RUN apt-get install -y git curl gcc automake libtool make flex bison
RUN mkdir virustotal
RUN cd virustotal ; git clone https://github.com/virustotal/yara
WORKDIR /go/virustotal/yara
ENV YARA_SRC /go/virustotal/yara
RUN ./bootstrap.sh && ./configure && make -C ${YARA_SRC} && make -C ${YARA_SRC} install
ENV LD_LIBRARY_PATH $LD_LIBRARY_PATH:/usr/local/lib
#libyara3 should be loaded now
ENV PATH $PATH:$HOME/.local/bin
WORKDIR /go
ENTRYPOINT ["/bin/bash"]
#entrypoint is bash , with args from Command array
CMD ["-c","./s3yarascanner"]