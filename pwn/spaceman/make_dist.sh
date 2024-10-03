temp_dir=$(mktemp -d)
trap "rm -r $temp_dir" EXIT

echo "bctf{fake_flag}" > "$temp_dir/flag.txt"
cp spaceman spaceman.c Dockerfile Makefile run.sh "$temp_dir"

out=$(pwd)
cd "$temp_dir"
zip export.zip spaceman spaceman.c Dockerfile Makefile run.sh flag.txt
mv export.zip "$out"/export.zip
