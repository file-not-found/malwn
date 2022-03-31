rule cs_config_data{
strings:
    $ = { 2e 2f 2e 2f 2e 2c }
    $ = { 69 6b 7a }
    $ = { 7e 61 7d 7a }
    $ = { 2e 26 2e 2d 2f 2e }
condition:
    all of them
}
