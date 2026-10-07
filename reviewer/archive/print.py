from testset_parser import parse_testset
s = [x for x in parse_testset() if x["category"] == "clean"]
for x in s[:5]:
    print("---", x["lang"], "|", x["desc"])
    print(x["code"][:400])