# google-play


## Motivation

Yes, my friends. These are completely untested go bindings for the google-play API.
Why would anyone do that you ask?
Reasons.
No honestly I just wanted some stable bindings I could use for my new pet-peeve language go.

## Installation

Note: The example is not working due to an Authentication error which I am currently investigating
Apparently our friends @google changed their auth gateway.

```
go mod download
go build -o build/example main/example.go
./build/example
```

## Credits

Thanks to my dude [googleplay-api](https://github.com/NoMore201/googleplay-api) assembling this code was a matter of
1 day (full of cursing etc.)
Thanks for your efforts
