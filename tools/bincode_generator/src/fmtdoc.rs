pub struct FmtDoc<T>(pub T);

impl std::fmt::Display for FmtDoc<(&'_ str, &'_ str)> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.1.lines().count() == 1 {
            return writeln!(f, "{}/** {} */", self.0.0, self.0.1);
        }
        writeln!(f, "{}/**", self.0.0)?;
        for line in self.0.1.lines() {
            writeln!(f, "{} * {}", self.0.0, line)?;
        }
        writeln!(f, "{} */", self.0.0)?;
        Ok(())
    }
}
