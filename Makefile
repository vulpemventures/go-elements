## help: prints this help message
help:
	@echo "Usage: \n"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'

test: 
	export API_URL=http://localhost:3001; \
	export API_BTC_URL=http://localhost:3000; \
	go test -count=1 -v ./... 

## fmt: Go Format
fmt:
	@echo "Gofmt..."
	@gofmt -w -l .
