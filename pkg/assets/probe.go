// Code generated by go-bindata. DO NOT EDIT.
// sources:
// ebpf/bin/probe.o

package assets


import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}


type asset struct {
	bytes []byte
	info  fileInfoEx
}

type fileInfoEx interface {
	os.FileInfo
	MD5Checksum() string
}

type bindataFileInfo struct {
	name        string
	size        int64
	mode        os.FileMode
	modTime     time.Time
	md5checksum string
}

func (fi bindataFileInfo) Name() string {
	return fi.name
}
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}
func (fi bindataFileInfo) MD5Checksum() string {
	return fi.md5checksum
}
func (fi bindataFileInfo) IsDir() bool {
	return false
}
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _bindataProbeO = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xec\x58\x4f\x68\x1c\x55\x18\xff\x66\x37\xc9\x6e\xb2\x6d\xba\x4d\xbb\x75\xb3\xad\x34\x07\xc1\x10\x35\xff\x5a\x25\xed\xc5\x50\x50\x83\xb4\x10\x8a\x68\x04\xe9\x64\x33\x99\x36\x6b\x92\xcd\xba\x33\xa9\x9b\xa4\x62\x3d\x14\x4a\x4f\x39\x54\x0d\xa5\x60\x6a\x45\x7b\x11\x73\x4b\x40\x70\x73\xa8\x90\x43\x0f\x01\x3d\x04\x8b\xb0\xde\x16\x3c\x34\x42\xa1\x39\xd4\x8c\xbc\xf7\xbe\xd9\x79\xf3\xcd\x4c\xb2\xc5\x42\x72\xc8\x83\xf6\x97\xef\x37\xef\xfb\xf7\xde\xf7\xbd\x37\x3b\x9f\xbf\x75\xf6\xed\x90\xa2\x80\x3d\x14\x78\x02\x8e\xe4\x8c\x52\xb3\xf3\x77\x2f\xfe\xdf\x0c\x0a\x14\x8f\x08\x2e\x49\x94\xb4\xd4\x53\x8b\x61\xf1\x5b\x21\x47\x42\x00\x4f\x2d\xcb\xa2\xf3\xae\x71\x9f\x00\x09\x38\xcd\xe5\x45\x45\xc8\x0f\xe3\x51\x2e\xa7\xef\x08\x3b\x33\xa9\xb2\x65\xcf\x6f\x64\x72\xc3\x7a\x45\xae\xe5\x72\xc9\xe3\xaf\x6c\x59\x56\xf1\x2e\xca\x61\x80\x92\x65\x59\x8b\x11\xff\x78\x17\x6b\x9c\x78\x42\x3e\xcf\x2f\x29\x00\x2d\x00\xf0\x29\x62\x42\x79\x89\xf3\x33\xd3\x6b\x22\xbe\xe9\x55\x8e\x53\x77\xd6\x31\xde\x15\x94\x45\xdc\x5a\x4a\xcc\x2b\xa6\xd1\x7f\x88\xf8\x0f\xb3\x20\x85\xff\xa3\x6c\x7e\xc3\x6a\x25\x3f\xb6\x12\x97\x00\xfd\x23\x16\xbf\xc3\xbc\x6a\x00\x56\x58\x9e\x01\x76\x8b\x61\xb4\x5f\x0b\x90\x44\x7b\xcd\x3e\xf6\x12\xd0\x50\x59\x7f\x11\xef\x7d\xcf\x7a\xde\xdf\x72\xff\x42\x64\xff\xd0\x2f\xce\xfb\x52\x9a\xcf\xf6\xab\x58\x87\xf1\x46\xdd\xf6\xb4\x1b\xcf\x56\x37\x45\xdc\xcf\x44\x64\x9f\xd8\x8f\x1b\xfe\x75\x42\xeb\x22\x38\x0f\xb1\x60\x53\xf8\xfc\x38\xd6\xf7\xc3\x4b\xfe\xf9\xd8\xf5\xef\xd4\xe1\x86\xcb\xbf\x1d\x5f\xf1\x13\x81\x76\xfd\x68\xa9\xc7\x96\x5f\xfe\xc5\x2f\x04\x7a\xeb\x4d\x2c\x98\x9c\xc7\xe3\x2d\xf3\x78\x5f\xac\xaf\xa7\x2f\xbd\xeb\xb1\xbe\xa5\x9d\x73\x22\x6f\xd2\x97\x33\xd3\x62\x9d\xd3\x95\x7a\xf7\xf6\x5f\x89\xf4\xdf\xc6\x73\xed\xbf\xd3\x18\x07\xed\xbf\x32\xe9\xbf\x52\xf5\xfd\x57\x27\xf7\xdf\xef\x56\x55\xfb\xb1\x6b\xfb\x59\x14\xe6\x62\x9d\xd8\x37\xed\xe3\x67\xed\x67\xf1\xe0\xe1\x20\xe6\x1f\x45\xfb\x88\x89\xe8\xce\x9c\x17\xdb\xf7\x95\x38\x3f\xb6\xaf\x1f\x6f\x3f\x6d\x7d\x3f\x25\xc4\x7e\xd4\xbb\x9f\x6b\xb7\x36\x3c\x79\x6f\x6c\x75\x5e\x61\xbf\x27\xa2\x31\x8e\x33\xd3\xd8\x3f\xb7\xca\xcf\xe7\x9c\x1a\xf1\x5f\xc7\xe2\x21\x81\xe9\x2e\x11\xc0\x22\xd6\xd5\x68\x9b\x58\x2f\xad\x4d\xe4\x31\xd3\x86\xf1\xb4\x61\x1f\xb5\x95\x10\xb1\xcf\xda\x56\x11\x57\x10\x97\x11\x97\x10\x17\x10\xef\x21\xce\x23\xce\x21\xce\x22\x5e\x47\xbc\x8a\x58\x40\xcc\x21\x8e\x20\x0e\x22\x0e\x20\xf6\x23\xf6\x21\xf6\x22\xf6\x20\x76\x22\xb6\x22\xb6\x20\x26\x11\xe3\x88\x51\x44\x40\xdc\xd8\xc4\xfc\x11\xcb\x88\x25\xc4\x35\xc4\x55\xc4\x15\xc4\x65\xc4\x25\xc4\x05\xc4\x7b\x88\xf3\x1c\x3f\x50\x00\x2c\x0b\xe0\x00\xee\x43\xf1\x7b\xdc\xe7\x3a\x80\xf9\x4d\xa7\xdf\xd9\xbe\x5c\x50\xc4\x3e\xbf\xe6\x53\xc7\xc5\x21\x5a\x07\xfb\x2b\x72\xa3\xd4\xff\x5a\xc3\x6d\xee\xd7\xee\x2f\x2d\x35\xb7\x49\xeb\xeb\xf6\xa6\xfb\x7c\x9e\xdb\xf4\xd6\x1b\x3d\x97\x69\x5d\xb1\x2e\x62\x53\xe2\x18\xcf\xde\x70\x86\x82\xeb\xc2\x3b\x2e\xbe\xd3\xd1\xec\xae\x11\xc2\xba\x89\xe2\xdf\x7b\xc3\x19\x11\x5c\x9b\x0d\x76\xc4\xb7\xee\x74\x34\xbb\x6b\xd4\xec\x74\x00\xbb\x78\xb0\xf3\x86\xdd\x1d\x35\x7b\x67\xb1\x67\x28\x58\x3b\xbc\x7e\xf6\x8a\xc8\x35\xde\xe9\x3f\x0b\x9b\x96\xc5\xdf\x83\xec\x6b\x4a\x99\x3e\x0f\xd1\x2b\x31\x85\xfd\xaa\x4e\xe2\x3f\x7b\x74\x4a\x07\xf6\x31\x00\x38\x29\x3d\x5b\x25\xb6\xd9\xf3\xf7\x24\x79\x30\xec\x7d\x6e\x4a\x72\x9f\xe2\x7d\x7e\x53\x92\x07\xaa\xbc\x2c\xe6\x79\x1f\xfc\x63\x51\xfe\x01\xb7\x1f\x86\x16\x62\xe7\x37\xce\xd7\xc2\x32\x99\xff\x88\xf3\x11\xe8\x27\x71\x97\x91\x9f\x27\xf3\x7f\x41\xbe\x93\xfe\x1e\x44\xbe\x4c\xf8\xbf\x38\x5f\x0f\xb3\xc4\xce\xaf\xc8\xf7\x90\xf5\xf8\x83\xcb\x31\xe8\xf3\x59\x87\x30\x84\xbd\x24\xe7\x6b\x03\xf8\x48\x00\x5f\x1f\xc0\xc7\x3c\xdc\x57\x00\x70\x10\x0e\x57\x64\xbb\xb5\xae\x70\x3e\xe1\xe1\x6f\x70\xbe\xa9\xc2\x1f\xc3\xfc\xde\xe4\xfc\x7e\x0f\xaf\x04\xbc\x3a\xbd\xab\xf8\xf3\x7f\x02\x40\x93\x94\x97\x5d\x6f\x0f\x38\xef\xe4\x65\xd7\xd9\x39\xee\xf7\x80\xc7\xef\xa9\x00\xfb\x17\xf8\xfc\xb8\x67\x7e\x17\xe7\x1b\x3d\xfc\x71\xce\x1f\xf4\xf0\x39\xce\x1f\xf2\xf0\xe7\x15\x16\xa7\xb3\xce\x76\xbd\xff\xc8\xe3\x77\xf6\xd7\xae\xaf\x9f\x39\xef\xec\xaf\xdd\x7f\xf6\x67\x25\xf1\x1b\x01\xa0\x53\x92\x99\xd7\x25\x49\x3e\x0a\x00\x6b\x92\xdc\x0c\x50\xa9\x3b\x06\x29\x00\x98\x95\x64\xd6\x93\xeb\x92\x9c\x94\xcf\x0d\xf4\xd7\x43\xfc\x5d\x27\xfe\x7a\x25\x99\x55\xcf\x55\x49\x7e\x91\xf5\x2f\xb1\xb7\x42\xec\xc9\xf1\x31\x7b\x03\x8a\x3b\xfe\x25\x12\x7f\x34\xe4\x96\x07\x43\xee\x7c\x96\x43\xee\x7c\x5a\xc2\x6e\xb9\x87\xc4\x9b\x23\xf1\xce\x92\x78\x97\x48\xbc\x40\xe2\x95\xe3\x63\xdd\xd0\x1a\x72\xdb\x3b\x26\xe9\xc7\x88\x7f\x76\x26\x0f\x48\x32\xeb\x9a\x82\x24\xb3\x2a\x9c\x93\x64\x5e\xdd\x17\x33\x63\xa6\x9e\x57\x27\x0d\x3d\xaf\x0e\x65\xb2\xe9\xfc\x14\xb4\x9b\x7a\xc1\x84\xf1\x74\xce\xe8\x30\xf3\x69\x4d\x57\xf5\xcb\x7a\xd6\x34\x04\x63\x98\xe9\xbc\xa9\xda\x92\x36\x31\x99\x35\xf5\x3c\x4a\x63\x13\x86\xa9\x72\x15\x67\xb2\x36\xea\x62\xf8\xdf\xc3\x6a\x2e\x33\x6c\x80\x7a\x59\xcf\x1b\x99\x89\xac\x78\x22\x9c\xab\xb9\xb4\x39\x02\xea\x58\x46\xd3\xb3\x86\x0e\xed\x79\x7d\xac\x5d\x1f\x51\x2f\xe6\xd3\xe3\x3a\x4c\xe6\xf2\x13\x43\xba\x3a\xc9\x8d\xc0\x64\x5e\x37\x5d\xc4\xa8\x87\x70\x49\xcc\x96\xb0\xd0\x21\x33\xb6\x92\x4c\x8e\xfa\x92\x2e\xc6\xd0\xb3\xc3\xaa\x94\x1f\x5c\x9c\xcc\x6a\x6a\x66\x18\xb8\x94\x9b\xc8\x64\x4d\x55\x35\xb4\x11\x7d\xd8\x86\x5c\x7e\x42\xd3\x0d\x43\xd5\x0b\xba\xc6\x0d\x3a\x33\x3b\xf8\x8c\x0e\x9f\x79\xe3\xe9\x4c\xb6\x5d\x83\x76\xc3\xcc\x9b\xe9\x21\x68\x37\xa6\xc6\x19\x9e\x3d\x73\xa6\x5b\x3d\x25\xe0\x0d\x06\x27\xd4\xd7\x19\x74\x0a\xe8\x52\x4f\x30\x38\xa9\x76\x8b\x67\xdd\x62\x26\x42\x57\x37\xfc\xef\xf1\x83\x02\xbe\xb7\x4a\xf9\x05\x81\x4f\xc8\xfd\x44\xdf\x3b\x0f\x23\x57\x47\xf8\xde\x00\x7f\xf4\xd5\xec\xd1\x36\xfa\xf4\x9e\x25\x9f\xd3\xe1\x6f\x7e\x8b\x7a\xc7\x1a\x5e\x4d\x76\x1f\x27\x41\xe4\x69\xeb\x57\xce\x33\xc5\xdf\x7f\x0e\xfd\xd2\xf7\x1d\xea\xff\xdf\x00\xff\x7d\xf8\xbd\xae\x53\xf2\x5f\xeb\xe3\xff\x95\x00\xff\xbd\xb8\x29\xf4\x7d\x8a\xfa\x7f\x59\xf1\xf7\x5f\x40\xff\x0b\x92\xff\x88\x8f\xff\x23\x01\xfe\xe7\x91\xa0\xef\x6b\xd4\x7f\x53\x80\xff\x56\xac\x9f\x7e\xc9\x7f\xbd\x8f\xff\x2b\x01\xfe\xcb\x78\xc5\xd3\xf7\x41\xea\xbf\x10\x94\x3f\xfa\x6f\x91\xfc\xc7\x7c\xfc\x9f\xc6\xfa\xa3\x3d\xd0\x2b\x3e\x7f\x57\xee\x6d\x7b\xd0\xfa\x7d\x35\x40\xff\xa3\x58\x75\xfa\x7d\x01\xfa\x85\x7d\xd5\xe9\x7f\x18\xa0\x7f\x73\x7f\x75\xfa\xa9\x00\xfd\x85\xc6\xea\xf4\xaf\x05\xe8\x3f\x38\x50\x9d\xfe\x68\x80\x7e\x39\x5e\x9d\xfe\xd7\x01\xfa\x35\x4d\xfe\xf3\xe9\xf9\xf5\x59\x80\x7e\x34\x40\x9f\xca\x77\x51\x9f\xbe\xae\xc7\x51\x7f\x81\xda\x25\xf2\x37\x01\xe7\xc7\x9c\x4f\xff\x1c\xf1\xa9\xdf\x9f\x14\xff\xef\x6b\xcb\xe8\x3f\x29\xbd\xe7\xc4\x25\x7d\xfb\xf7\xde\x7f\x01\x00\x00\xff\xff\x52\xa7\x87\x2d\x20\x20\x00\x00")

func bindataProbeOBytes() ([]byte, error) {
	return bindataRead(
		_bindataProbeO,
		"/probe.o",
	)
}



func bindataProbeO() (*asset, error) {
	bytes, err := bindataProbeOBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{
		name: "/probe.o",
		size: 8224,
		md5checksum: "",
		mode: os.FileMode(420),
		modTime: time.Unix(1637923309, 0),
	}

	a := &asset{bytes: bytes, info: info}

	return a, nil
}


//
// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
//
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrNotExist}
}

//
// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
// nolint: deadcode
//
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

//
// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or could not be loaded.
//
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrNotExist}
}

//
// AssetNames returns the names of the assets.
// nolint: deadcode
//
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

//
// _bindata is a table, holding each asset generator, mapped to its name.
//
var _bindata = map[string]func() (*asset, error){
	"/probe.o": bindataProbeO,
}

//
// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
//
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, &os.PathError{
					Op: "open",
					Path: name,
					Err: os.ErrNotExist,
				}
			}
		}
	}
	if node.Func != nil {
		return nil, &os.PathError{
			Op: "open",
			Path: name,
			Err: os.ErrNotExist,
		}
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}


type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}

var _bintree = &bintree{Func: nil, Children: map[string]*bintree{
	"": {Func: nil, Children: map[string]*bintree{
		"probe.o": {Func: bindataProbeO, Children: map[string]*bintree{}},
	}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	return os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}
