#!/bin/bash
cd build
cmake .. -DBACKEND=Linux
make router_hal
make