# Load specified SVD and generate peripheral memory maps & structures.

class MemoryRegion:
	def __init__(self, name, start, end):
		self.name = name
		self.start = start
		self.end = end

	def length(self):
		return self.end - self.start

def reduce_memory_regions(regions):
	for i in range(len(regions)):
		r1 = regions[i]
		for j in range(len(regions)):
			r2 = regions[j]
			# Skip self
			if i == j:
				continue
			if r1.end < r2.start:
				continue
			if r2.end < r1.start:
				continue

			# We are overlapping, generate larger area and call
			# reduce_memory_regions again.
			regions[i].start = min(r1.start, r2.start)
			regions[i].end = max(r1.end, r2.end)
			regions[i].name = r1.name + "_" + r2.name
			regions.remove(regions[j])
			return reduce_memory_regions(regions)
	return regions

def calculate_peripheral_size(peripheral, default_register_size):
	size = 0
	for register in peripheral.registers:
		register_size = default_register_size if not register._size else register._size
		size = max(size, register.address_offset + register_size/8)
	return size



