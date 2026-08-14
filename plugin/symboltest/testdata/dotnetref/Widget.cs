// Widget.cs is part of the offline dotnetref fixture: its declarations realize the
// §4.3 categories the .NET reference profile targets, so dotnetanalysis.IndexSymbols
// emits real symbols for them. It has no external dependencies and is read lexically
// (never built or run). Mirrors testdata/goref/widget.go for C#.
namespace Symboltest.DotNetRef
{
    // types (§4.3 row 2): the class type Widget.
    public class Widget
    {
        private readonly string _name;

        // constructors (§4.3 row 5): an explicit parameterless constructor; its
        // ECMA-335 metadata name is ".ctor".
        public Widget()
        {
            _name = "widget";
        }

        // methods (§4.3 row 4): an instance method taking one object parameter.
        public string Render(object value)
        {
            return _name + ":" + value;
        }

        // overloads/generics (§4.3 row 6): a 1-arity generic method whose identity is
        // the positional arity segment `1(string) — distinct from its non-generic
        // sibling below (which shares Name but differs in Descriptor).
        public T DeserializeObject<T>(string text)
        {
            return default;
        }

        // ...the non-generic sibling of the overload pair — same Name, no arity segment.
        public object DeserializeObject(string text)
        {
            return text;
        }

        // generated symbols (§4.3 row 8): an async method. The compiler synthesizes the
        // state-machine type <FetchAsync>d__0 (nested in Widget, Generated=true) — the
        // generated symbol the profile targets. It exists only in compiled IL, so the
        // pure-source scanner never observes it (SYMBOLS.md ⚑SM; PLAN-250 closes it).
        public async System.Threading.Tasks.Task<int> FetchAsync()
        {
            await System.Threading.Tasks.Task.Yield();
            return 0;
        }

        // nested declarations (§4.3 row 7): a type nested under Widget; its Enclosing is
        // the namespace + outer type.
        public class Inner
        {
            public void Ping()
            {
            }
        }
    }
}
