package backend

import (
	"encoding/json"
)

func GeneralLessThan(ip, jp interface{}) bool {
	// If both are nil, the Less is i < j == false
	if ip == nil && jp == nil {
		return false
	}
	// If ip is nil, the Less is i < j == true
	if ip == nil {
		if _, ok := jp.(bool); ok {
			return jp.(bool)
		}
		return true
	}
	// If jp is nil, the Less is i < j == false
	if jp == nil {
		return false
	}

	if _, ok := ip.(string); ok {
		return ip.(string) < jp.(string)
	}
	if _, ok := ip.(bool); ok {
		return jp.(bool) && !ip.(bool)
	}
	if _, ok := ip.(int); ok {
		return ip.(int) < jp.(int)
	}

	return false
}

func GeneralGreaterThanEqual(ip, jp interface{}) bool {
	// If both are nil, the Less is i >= j == true
	if ip == nil && jp == nil {
		return true
	}
	// If ip is nil, the Less is i >= j == false
	if ip == nil {
		if _, ok := jp.(bool); ok {
			return !jp.(bool)
		}
		return false
	}
	// If jp is nil, the Less is i >= j == true
	if jp == nil {
		return true
	}

	if _, ok := ip.(string); ok {
		return ip.(string) >= jp.(string)
	}
	if _, ok := ip.(bool); ok {
		return ip.(bool) || ip.(bool) == jp.(bool)
	}
	if _, ok := ip.(int); ok {
		return ip.(int) >= jp.(int)
	}
	return false
}

func GeneralGreaterThan(ip, jp interface{}) bool {
	// If both are nil, the Less is i > j == false
	if ip == nil && jp == nil {
		return false
	}
	// If ip is nil, the Less is i > j == false
	if ip == nil {
		return false
	}
	// If jp is nil, the Less is i > j == true
	if jp == nil {
		if _, ok := ip.(bool); ok {
			return ip.(bool)
		}
		return true
	}

	if _, ok := ip.(string); ok {
		return ip.(string) > jp.(string)
	}
	if _, ok := ip.(bool); ok {
		return ip.(bool) && !jp.(bool)
	}
	if _, ok := ip.(int); ok {
		return ip.(int) > jp.(int)
	}
	return false
}

func GeneralValidateParam(param *Param, s string) (interface{}, error) {
	var obj interface{}
	err := json.Unmarshal([]byte(s), &obj)
	if err != nil {
		// If type is string, then just use the value
		// we leave the json parsing so that we can test quoted strings.
		if tv, ok := param.TypeValue(); ok {
			if is, ok := tv.(string); ok && is == "string" {
				obj = s
			} else {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	if err := param.ValidateValue(obj, nil); err != nil {
		return nil, err
	}
	return obj, nil
}
