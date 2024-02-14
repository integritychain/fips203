use crate::Q;

// While Z is nice, simple and correct, the performance is suboptimal.
// This will be addressed (particularly in matrix operations etc) 'soon',
// potentially as a 256-entry row.

/// Stored as u16, but arithmetic as u32 (so we can multiply/reduce/etc)
#[derive(Clone, Copy, Default)]
pub struct Z(u16);


#[allow(clippy::inline_always)]
impl Z {
    const M: u64 = 2u64.pow(32) / (Self::Q64);
    #[allow(clippy::cast_possible_truncation)]
    const Q16: u16 = Q as u16;
    const Q64: u64 = Q as u64;

    pub fn get_u16(self) -> u16 { self.0 }

    pub fn get_u32(self) -> u32 { u32::from(self.0) }

    pub fn set_u16(&mut self, a: u16) { self.0 = a }

    #[inline(always)]
    pub fn add(self, other: Self) -> Self {
        let sum = self.0.wrapping_add(other.0);
        let (trial, borrow) = sum.overflowing_sub(Self::Q16);
        let result = if borrow { sum } else { trial }; // TODO Not quite CT
        Self(result)
    }

    #[inline(always)]
    pub fn sub(self, other: Self) -> Self {
        let (diff, borrow) = self.0.overflowing_sub(other.0);
        let trial = diff.wrapping_add(Self::Q16);
        let result = if borrow { trial } else { diff }; // TODO Not quite CT
        Self(result)
    }

    #[inline(always)]
    pub fn mul(self, other: Self) -> Self {
        let prod = u64::from(self.0) * u64::from(other.0);
        let quot = prod * Self::M;
        let quot = quot >> (32);
        let rem = prod - quot * Self::Q64;
        let (diff, borrow) = rem.overflowing_sub(Self::Q64);
        let result = if borrow { rem } else { diff }; // TODO Not quite CT
        Self(u16::try_from(result).unwrap())
    }
}
