const res = await fetch("https://x.example/boot");
process.stdout.write(await res.text());
