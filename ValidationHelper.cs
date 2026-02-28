public static class ValidationHelper
{
    
    public static bool IsValidInput(string input)
    {
        foreach (char c in input)
        {
            if (!char.IsLetterOrDigit(c) && c != '@' && c != '#' && c != '$')
                return false;
        }
        return true;
    }

}