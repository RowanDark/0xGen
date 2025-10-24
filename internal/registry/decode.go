package registry

// Decode parses registry dataset JSON from memory, validates, and normalises
// the result.
func Decode(data []byte) (Dataset, error) {
	var dataset Dataset
	if err := dataset.UnmarshalJSON(data); err != nil {
		return Dataset{}, err
	}
	if err := dataset.Validate(); err != nil {
		return Dataset{}, err
	}
	dataset.normalise()
	return dataset, nil
}
