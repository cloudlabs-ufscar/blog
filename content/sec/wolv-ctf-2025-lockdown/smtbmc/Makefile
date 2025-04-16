all: top/engine_0/trace0.yw
	@python -c "import json;print(f'wctf{{{int('0b'+json.load(open('$<'))['steps'][0]['bits'],2).to_bytes(48//8).decode()}}}')"

top/engine_0/trace0.yw: top.sby top.v
	sby -f "$<"

top.v: top.v.tmpl
	gomplate -f "$<" -o "$@"
