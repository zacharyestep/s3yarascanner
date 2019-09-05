FROM ubuntu:18.04
ARG RULESDIR
ARG BINARYDIR
RUN mkdir $RULESDIR
RUN mkdir $BINARYDIR
RUN mkdir ./db
WORKDIR /go
RUN echo $PWD
COPY ./s3yarascanner /go/s3yarascanner
RUN ls .
RUN chmod +x s3yarascanner
ENTRYPOINT ["/bin/bash"]
CMD ["-c","./s3yarascanner"]