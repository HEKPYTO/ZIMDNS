const Fixture = @import("gcli_dns").golden_fixture.Fixture;

test "simple A query golden fixture" {
    const text = @embedFile("simple-a-query.gdns-fixture");
    const fixture = try Fixture.parse(text);
    try fixture.run();
}
