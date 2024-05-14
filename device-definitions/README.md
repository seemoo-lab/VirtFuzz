# Device Definition
The device definition is expected as valid JSON object containing the following fields:

* **virtio_id** (required): The 1-byte long id of the VirtIO device according to the specification
* **virtqueue_num** (required): The 2-byte long number of Virtqueues.
* **virtqueue_tx** (optional): The virtqueue index on which frames are transmitted *from the drivers point of view*.
* **virtqueue_tx** (optional): The virtqueue index on which frames are received *from the drivers point of view*. When it is not specified, fuzzing is not possible.
* **features** (required): An array of 2-byte integers, indicating the supported features of the VirtIO device.
* **config** (required): A string containing the hexadecimal configuration of the device.
* **command_line_params** (optional): An array of strings that specify additional kernel command line parameters when using this device.

Please see the existing definitions as example.
They are deserialized to the `DeviceConfiguration` structs of the VirtFuzz library.