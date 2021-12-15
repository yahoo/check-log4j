NAME= check-log4j

PREFIX?=/usr/local

help:
	@echo "The following targets are available:"
	@echo "install  install ${NAME} under ${PREFIX}"

install:
	mkdir -p ${PREFIX}/bin ${PREFIX}/share/man/man1
	install -c -m 555 src/${NAME}.sh ${PREFIX}/bin/${NAME}
	install -c -m 444 doc/${NAME}.1 ${PREFIX}/share/man/man1/${NAME}.1
