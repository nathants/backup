package cli

var Commands = map[string]func(){}
var Args = map[string]any{}

func Register(name string, args any, fn func()) {
	Commands[name] = fn
	Args[name] = args
}
