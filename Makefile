PROG_NAME := "snmp-prom"
IMAGE_NAME := "pschou/snmp-prom"
VERSION := "0.1"


build:
	GO111MODULE=off CGO_ENABLED=0 go build -o ${PROG_NAME} main.go

docker: build
	docker build -f Dockerfile --tag ${IMAGE_NAME}:${VERSION} .
	#docker push ${IMAGE_NAME}:${VERSION}; \
	#docker save -o pschou_${PROG_NAME}.tar ${IMAGE_NAME}:${VERSION}
