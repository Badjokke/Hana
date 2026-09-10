echo "Generating ebpf assets"
go generate
echo "Compiling"
go build
