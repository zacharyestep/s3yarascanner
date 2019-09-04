 cd ${YARA_SRC} \
  && ./bootstrap.sh \
  && ./configure \
  && make -C ${YARA_SRC} \
  && make -C ${YARA_SRC} install 
