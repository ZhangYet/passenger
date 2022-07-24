#!/usr/bin/env bash
API="https://www.dictionaryapi.com/api/v3/references/collegiate/json/"

if [ ! ${DICT_TOKEN} ]; then
    echo "No DICT_TOKEN found"
    exit 1
fi

word=$1

data=`curl "${API}/${word}?key=${DICT_TOKEN}" | jq`

function found_word() {
    string_type='"string"'
    _type=`echo $1 | jq '.[0]' | jq 'type'`
    if [ $_type = $string_type ]; then
	return 1
    fi
    return 0
}

found=`found_word "$data"`

if [[ $found -eq 1 ]]; then
    echo "$word not found"
    exit 1
fi

echo "* $word :bagpie:" > $word.org
echo $data | jq 'map(.shortdef)' | jq 'flatten' | jq '.[]?' | sed 's/\"//g'  >>  $word.org

