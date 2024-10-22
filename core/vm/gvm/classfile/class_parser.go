package classfile

func Parse(classData []byte) (cf *ClassFile, err error) {
	reader := newClassReader(classData)
	cf = &ClassFile{}
	if err := cf.read(&reader); err != nil {
		return nil, err
	}
	return cf, nil
}
