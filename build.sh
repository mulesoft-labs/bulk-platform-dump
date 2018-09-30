#!/bin/sh
go build
tar -czvf bulk-platform-dump-darwin-amd64.tar.gz bulk-platform-dump
rm bulk-platform-dump