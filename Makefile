include $(GOROOT)/src/Make.inc

GOFMT=gofmt -s
TARG=vmac
GOFILES=\
	vmac.go\

include $(GOROOT)/src/Make.pkg

format:
	${GOFMT} -w *.go
