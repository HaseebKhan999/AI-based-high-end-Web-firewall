import { formatInTimeZone } from 'date-fns-tz';

/**
 * Format date to GMT+5 timezone
 * @param {string|Date} dateString - Date string or Date object
 * @param {string} formatStr - Format string (default: 'MMM dd, yyyy HH:mm:ss')
 * @returns {string} Formatted date string in GMT+5
 */
export const formatDateGMT5 = (dateString, formatStr = 'MMM dd, yyyy HH:mm:ss') => {
  if (!dateString) return 'N/A';
  
  try {
    const date = typeof dateString === 'string' ? new Date(dateString) : dateString;
    
    // GMT+5 timezone (Asia/Karachi, Asia/Tashkent, etc.)
    const timeZone = 'Asia/Karachi'; // GMT+5
    
    return formatInTimeZone(date, timeZone, formatStr);
  } catch (error) {
    console.error('Date formatting error:', error);
    return dateString;
  }
};

/**
 * Format date with timezone indicator
 * @param {string|Date} dateString - Date string or Date object
 * @returns {string} Formatted date string with GMT+5 indicator
 */
export const formatDateWithTimezone = (dateString) => {
  return formatDateGMT5(dateString, 'MMM dd, yyyy HH:mm:ss (GMT+5)');
};

