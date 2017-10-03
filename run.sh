#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo "skycoin binary dir:" "$DIR"
pushd "$DIR" >/dev/null
<<<<<<< HEAD

go run cmd/amltoken/amltoken.go --gui-dir="${DIR}/src/gui/static/" $@

=======
go run cmd/skycoin/skycoin.go --gui-dir="${DIR}/src/gui/static/" $@
>>>>>>> f725fbbeacf65c448fc6e639cc64c966cc61c878
popd >/dev/null
