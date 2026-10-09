package auth_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// environmentReaders are the os functions that consult the process
// environment, directly or to locate a user directory. Consumers supply every
// value explicitly, so library code calls none of them.
var environmentReaders = map[string]bool{
	"Getenv": true, "LookupEnv": true, "Environ": true, "ExpandEnv": true,
	"Setenv": true, "Unsetenv": true, "Clearenv": true,
	"UserHomeDir": true, "UserCacheDir": true, "UserConfigDir": true,
}

// TestLibraryKeepsNoAmbientState enforces that library code reads no
// environment variables, runs no init functions, and declares no mutable
// package-level variables. Sentinel errors and compiled regular expressions
// are immutable by convention and allowed.
func TestLibraryKeepsNoAmbientState(t *testing.T) {
	var problems []string

	fileSet := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path != "." && (strings.HasPrefix(entry.Name(), ".") || entry.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fileSet, path, nil, 0)
		if err != nil {
			return err
		}
		location := func(node ast.Node) string {
			position := fileSet.Position(node.Pos())
			return filepath.ToSlash(position.Filename) + ":" + strconv.Itoa(position.Line)
		}

		osName := ""
		for _, spec := range file.Imports {
			if importPath, _ := strconv.Unquote(spec.Path.Value); importPath == "os" {
				osName = "os"
				if spec.Name != nil {
					osName = spec.Name.Name
				}
			}
		}
		if osName != "" {
			ast.Inspect(file, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if ident, ok := selector.X.(*ast.Ident); ok && ident.Name == osName && environmentReaders[selector.Sel.Name] {
					problems = append(problems, location(selector)+": reads the environment via os."+selector.Sel.Name)
				}
				return true
			})
		}

		for _, declaration := range file.Decls {
			switch typed := declaration.(type) {
			case *ast.FuncDecl:
				if typed.Recv == nil && typed.Name.Name == "init" {
					problems = append(problems, location(typed)+": declares an init function")
				}
			case *ast.GenDecl:
				if typed.Tok != token.VAR {
					continue
				}
				for _, spec := range typed.Specs {
					value := spec.(*ast.ValueSpec)
					for index, name := range value.Names {
						if name.Name == "_" {
							continue
						}
						if index < len(value.Values) && immutableByConvention(value.Values[index]) {
							continue
						}
						qualified := file.Name.Name + "." + name.Name
						problems = append(problems, location(name)+": package-level variable "+qualified)
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(problems)
	for _, problem := range problems {
		t.Error(problem)
	}
}

// immutableByConvention reports values that are never reassigned in practice:
// sentinel errors and compiled regular expressions.
func immutableByConvention(value ast.Expr) bool {
	call, ok := value.(*ast.CallExpr)
	if !ok {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := selector.X.(*ast.Ident)
	if !ok {
		return false
	}
	switch pkg.Name + "." + selector.Sel.Name {
	case "errors.New", "regexp.MustCompile":
		return true
	}
	return false
}
