#define main netwatch_application_main
#include "../main.cpp"
#undef main
#include <cassert>
int main() {
    Network network;
    Target t=parseTarget("Test|127.0.0.1|12345|500|100|2");
    Stats s; Probe p;
    p.detail="REFUSED";
    s.update(t,p); assert(s.state=="SUSPECT" && s.streak==1);
    s.update(t,p); assert(s.state=="ALERT" && s.streak==2);
    p.ok=true; p.ms=150; p.detail="CONNECTED";
    s.update(t,p); assert(s.state=="SLOW" && s.streak==0);
    p.ms=50; s.update(t,p); assert(s.state=="UP");
    assert(s.checks==4 && s.successes==2 && s.total==200 && s.minimum==50 && s.maximum==150);
    assert(csv("=1+1")=="\"'=1+1\"");
    assert(csv("a\"b")=="\"a\"\"b\"");
    for(const auto& row: {"Bad|127.0.0.1|0|500|100|2", "Bad|999.1.1.1|80|500|100|2", "Bad|example.com|80|500|100|2", "Bad|224.0.0.1|80|500|100|2", "Bad|127.0.0.1|80x|500|100|2", "Bad|127.0.0.1|80|500|100|2|extra"}) {
        bool rejected=false;
        try { parseTarget(row); } catch(const std::exception&) { rejected=true; }
        assert(rejected);
    }
    bool duplicate=false;
    try { uniqueTarget(std::vector<Target>(1,t),t); } catch(const std::exception&) { duplicate=true; }
    assert(duplicate);
    std::cout << "Unit checks passed: states, metrics, CSV escaping, validation, duplicates.\n";
}
