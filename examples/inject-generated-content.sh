#!/bin/bash

# Exit on error
set -e

DOC_FILE_NAME=draft-ietf-cose-bls-key-representations.md
DOCFILE="../${DOC_FILE_NAME}"
NEWDOCFILE="${DOC_FILE_NAME}.new"

inject() {
  CRV="$1"
  SALT="$2"
  FORMAT="$3"
  CLARG="${CRV}:${SALT}:${FORMAT}"
  BLOCK_TAG="GENERATED CONTENT: Use examples directory -- ${CLARG}"

  # Print everything before the generated content block
  sed "/<!-- ${BLOCK_TAG} -->/,\$d" < "${DOCFILE}" > "${NEWDOCFILE}"

  # Print the generated content block
  echo "<!-- ${BLOCK_TAG} -->" >> "${NEWDOCFILE}"
  cargo run --release -- "${CLARG}" >> "${NEWDOCFILE}"
  echo "<!-- END ${BLOCK_TAG} -->" >> "${NEWDOCFILE}"

  # Print everything after the generated content block
  sed "0,/<!-- END ${BLOCK_TAG} -->/d" < "${DOCFILE}" >> "${NEWDOCFILE}"

  mv "${NEWDOCFILE}" "${DOCFILE}"
}

if [[ "$1" == "--check" ]]; then
  if ! git diff --exit-code --stat -- "${DOCFILE}"; then
    echo "Cannot check if generated content are up to date. Please commit or revert changes to ${DOC_FILE_NAME} first."
    exit 1
  fi
fi

for crv in BLS12381G1 BLS12381G2 BLS48581G1 BLS48581G2 ; do
  for salt in 0 1 ; do
    for format in jwk cwk cddl ; do
      inject "${crv}" "${salt}" "${format}"
    done
  done
done

if [[ "$1" == "--check" ]]; then
  if git diff --exit-code --stat -- "${DOCFILE}"; then
    echo "Generated content is up to date."
  else
    echo "Generated content is up not to date. Please run examples/inject-generated-content.sh and commit the results."
    exit 1
  fi
fi
