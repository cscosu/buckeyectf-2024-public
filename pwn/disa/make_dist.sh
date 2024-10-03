temp_dir=$(mktemp -d)
trap "rm -r $temp_dir" EXIT

echo "bctf{fake_flag}" > "$temp_dir/flag.txt"
cp disa disa.c disa.h Dockerfile Makefile "$temp_dir"

out=$(pwd)
cd "$temp_dir"
zip export.zip disa disa.c disa.h Dockerfile Makefile flag.txt
mv export.zip "$out"/export.zip
