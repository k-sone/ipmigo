ipmigo
======

**Work In Progress**

ipmigo is a golang implementation for IPMI client.

Supported Version
-----------------

* IPMI v2.0(lanplus)

Examples
--------

```go
package main

import (
    "fmt"

    "github.com/k-sone/ipmigo"
)

func main() {
    c, err := ipmigo.NewClient(ipmigo.Arguments{
        Version:       ipmigo.V2_0,
        Address:       "192.168.1.1:623",
        Username:      "myuser",
        Password:      "mypass",
        CipherSuiteID: 3,
    })
    if err != nil {
        fmt.Println(err)
        return
    }

    if err := c.Open(); err != nil {
        fmt.Println(err)
        return
    }
    defer c.Close()

    cmd := &ipmigo.GetPOHCounterCommand{}
    if err := c.Execute(cmd); err != nil {
        fmt.Println(err)
        return
    }
    fmt.Println("Power On Hours", cmd.PowerOnHours())
}
```

License
-------

MIT
