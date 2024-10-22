package classfile

func readConstantPool(reader *ClassReader) ([]ConstantInfo, error) {
	cpCount := int(reader.ReadUint16())
	cp := make([]ConstantInfo, cpCount)
	var err error

	// The constant_pool table is indexed from 1 to constant_pool_count - 1.
	for i := 1; i < cpCount; i++ {
		if cp[i], err = readConstantInfo(reader); err != nil {
			return nil, err
		}
		// http://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.4.5
		// All 8-byte constants take up two entries in the constant_pool table of the class file.
		// If a CONSTANT_Long_info or CONSTANT_Double_info structure is the item in the constant_pool
		// table at index n, then the next usable item in the pool is located at index n+2.
		// The constant_pool index n+1 must be valid but is considered unusable.
		switch cp[i].(type) {
		case int64, float64:
			i++
		}
	}

	return cp, nil
}
