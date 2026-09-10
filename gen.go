package main

//go:generate go tool bpf2go -tags linux hana kern/hana_kern.c kern/hana_kern.h kern/checksum.h
