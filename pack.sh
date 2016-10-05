#!/bin/bash
CONFIGURATION=$1
shift

for PACKAGE in $*; do
    cd /app/$PACKAGE
    dotnet restore
    dotnet pack --configuration=$CONFIGURATION
done